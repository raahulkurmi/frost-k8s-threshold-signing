#!/usr/bin/env bash
# deploy/aws/7c/bootstrap.sh STEP...: set up the Phase 7C hosts from the operator
# Mac (NOTES N67), after deploy/aws/provision-7c.sh phase1 [phase2]. Steps are
# idempotent enough to re-run individually:
#   build       linux/amd64 tools: k8s7c, frost-probe, tokenbench (bin/7c/)
#   nodes       node-setup.sh on cp, w1, w2 (containerd + kubeadm 1.36.5, pinned)
#   cluster     cp-init.sh on cp (kubeadm init, audit, flannel, manifest variants), join w1, w2
#   coord       coordinator node: Docker, repo clone at HEAD, images, B1 key
#   lg          load generator: tokenbench + admin kubeconfig (streamed cp -> lg via ssh, never on disk here)
#   deploy-t5   T-5-region: fresh certs + key ceremony, one share per signer host (deploy/multihost/deploy.sh)
#   deploy-tsame  T-same-region (phase 2), same
#   cp-tools    nginx static pod + config, switch/check/scale scripts, frost-probe on cp
#   smoke       use_system + check for every available system -> reports/aws/7c/bootstrap-checks.jsonl
#   all         everything above in order (deploy-tsame / T-same smoke only if phase 2 exists)
set -euo pipefail
cd "$(dirname "$0")/../../.."
REPO="$(pwd)"
# shellcheck disable=SC1091
source benchmark/k8s7c/lib.sh
D=deploy/aws/7c
SHA="$(git rev-parse HEAD)"
mkdir -p reports/aws/7c

step_build() {
  mkdir -p bin/7c
  ( cd benchmark && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "$REPO/bin/7c/k8s7c" ./k8s7c && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "$REPO/bin/7c/tokenbench" ./tokenbench )
  GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/7c/frost-probe ./test/e2e/probe
  shasum -a 256 bin/7c/* | sed 's#bin/7c/##'
}
step_nodes() {
  local h pids=""
  for h in cp w1 w2; do
    ( push "$h" $D/versions.env /tmp/versions.env && push "$h" $D/node-setup.sh /tmp/node-setup.sh \
      && on "$h" sudo bash /tmp/node-setup.sh /tmp/versions.env 2>&1 | sed "s/^/  [$h] /" ) &
    pids="$pids $!"
  done
  local p rc=0; for p in $pids; do wait "$p" || rc=1; done
  [[ $rc == 0 ]] || die "node setup failed"
}
step_cluster() {
  push cp $D/versions.env /tmp/versions.env; push cp $D/cp-init.sh /tmp/cp-init.sh
  push cp benchmark/single/apiserver-audit-policy/audit-policy.yaml /tmp/audit-policy.yaml; push cp bin/7c/k8s7c /tmp/k8s7c
  local out join
  out="$(on cp sudo bash /tmp/cp-init.sh /tmp/versions.env "$CP_PRIV" /tmp/audit-policy.yaml /tmp/k8s7c)" || die "kubeadm init failed"
  grep -v '^kubeadm join' <<<"$out" | sed 's/^/  [cp] /'
  join="$(grep '^kubeadm join' <<<"$out" | tail -1)"; [[ -n "$join" ]] || die "no join command"
  local w; for w in w1 w2; do
    # shellcheck disable=SC2086
    on "$w" sudo $join >/dev/null 2>&1 || die "$w join failed"; log "$w joined"
  done
  for _ in $(seq 1 90); do
    [[ "$(on cp kubectl get nodes --no-headers 2>/dev/null | awk '$2=="Ready"' | wc -l | tr -d ' ')" == 3 ]] && break; sleep 5
  done
  on cp kubectl get nodes -o wide
}
step_coord() {
  push coord $D/docker-setup.sh /tmp/docker-setup.sh
  on coord sudo bash /tmp/docker-setup.sh ubuntu
  on coord bash -c "set -e; if [ ! -d ~/repo/.git ]; then git clone -q --no-tags https://github.com/raahulkurmi/frost-k8s-threshold-signing.git ~/repo; fi; cd ~/repo; git fetch -q origin; git checkout -q --detach $SHA; ln -sfn ~/repo ~/tk8s; git log -1 --format='coordinator node clone at %h %s'"
  on coord bash -lc "cd ~/tk8s && docker build -q -f deploy/docker/Dockerfile.proxy -t frost-k8s/coordinator:dev . && docker build -q -f benchmark/b1signer/Dockerfile -t frost-k8s/b1signer:bench . && docker image ls --format '{{.Repository}}:{{.Tag}} {{.ID}}' | grep frost-k8s"
  on coord bash -c 'set -e; mkdir -p ~/tk8s/secrets-b1; umask 077; [ -s ~/tk8s/secrets-b1/key.pem ] || openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ~/tk8s/secrets-b1/key.pem 2>/dev/null; echo "B1 key (benchmark only): $(stat -c "%a %U" ~/tk8s/secrets-b1/key.pem)"'
}
step_lg() {
  push lg bin/7c/tokenbench /tmp/tokenbench; on lg bash -c 'install -m 0755 /tmp/tokenbench ~/tokenbench && rm /tmp/tokenbench'
  on cp sudo cat /etc/kubernetes/admin.conf | on_pipe lg bash -c 'umask 077; mkdir -p ~/.kube; cat > ~/.kube/config; chmod 600 ~/.kube/config'
  on lg bash -c "./tokenbench -h 2>&1 | head -1; grep -c 'server: https://$CP_PRIV:6443' ~/.kube/config"
}
step_deploy() { # t5 | tsame
  local topo="$S7/topology-$1.env"; [[ -f "$topo" ]] || die "$topo missing (phase 2 provisioned?)"
  deploy/multihost/deploy.sh "$topo"
}
step_cp_tools() {
  local conf; conf="$(mktemp)"
  sed -E "s#server 172\.30\.1\.11:9090#server $COORD_PRIV:9090#; s#server 172\.30\.1\.12:9090#server $COORD_PRIV:9091#; s#server 172\.30\.1\.13:9090#server $COORD_PRIV:9092#; s#grpc_ssl_trusted_certificate /etc/nginx/ca.crt;#grpc_ssl_trusted_certificate /etc/nginx/lb-tls/ca.crt;#" deploy/nginx-grpc.conf > "$conf"
  [[ "$(grep -c "server $COORD_PRIV:909[012]" "$conf")" == 3 && "$(grep -c 'lb-tls/ca.crt' "$conf")" == 1 ]] || die "nginx.conf rendering failed"
  push cp "$conf" /tmp/nginx.conf; rm -f "$conf"
  push cp $D/frost-nginx.yaml /tmp/frost-nginx.yaml; push cp $D/switch.sh /tmp/switch.sh; push cp $D/check.sh /tmp/check.sh
  push cp $D/scale-rep.sh /tmp/scale-rep.sh; push cp benchmark/single/scale-deploy.yaml /tmp/scale-deploy.yaml; push cp bin/7c/frost-probe /tmp/frost-probe
  on cp sudo bash -c 'set -e
    install -m 0644 /tmp/nginx.conf /etc/frost-7c/nginx.conf
    install -m 0600 /tmp/frost-nginx.yaml /etc/frost-7c/frost-nginx.yaml
    install -m 0644 /tmp/scale-deploy.yaml /etc/frost-7c/scale-deploy.yaml
    install -m 0755 /tmp/switch.sh /usr/local/bin/frost-7c-switch
    install -m 0755 /tmp/check.sh /usr/local/bin/frost-7c-check
    install -m 0755 /tmp/scale-rep.sh /usr/local/bin/frost-7c-scale-rep
    install -m 0755 /tmp/frost-probe /usr/local/bin/frost-probe
    install -d -m 0700 /etc/frost-7c/lb
    for f in tls.crt tls.key ca.crt; do [ -s /etc/frost-7c/lb/$f ] || install -m 0600 /etc/frost-7c/lb-t5/$f /etc/frost-7c/lb/$f; done
    install -m 0600 /etc/frost-7c/frost-nginx.yaml /etc/kubernetes/manifests/frost-nginx.yaml
    rm -f /tmp/nginx.conf /tmp/frost-nginx.yaml /tmp/switch.sh /tmp/check.sh /tmp/scale-rep.sh /tmp/scale-deploy.yaml /tmp/frost-probe
    stat -c "%n %U:%G %a" /var/run/frost-k8s /etc/frost-7c/lb /etc/frost-7c/lb/tls.key'
  for _ in $(seq 1 60); do on cp sudo test -S /var/run/frost-k8s/signer.sock && break; sleep 2; done
  on cp sudo test -S /var/run/frost-k8s/signer.sock || die "nginx socket not created"
  log "nginx static pod serving /var/run/frost-k8s/signer.sock on cp"
}
step_smoke() {
  local out=reports/aws/7c/bootstrap-checks.jsonl sys systems="B0 B1 T-5region-optimistic T-5region-strict"
  [[ -f "$S7/topology-tsame.env" ]] && systems="$systems T-sameregion-optimistic T-sameregion-strict"
  : > "$out"
  for sys in $systems; do use_system "$sys" /tmp/c7check.json; cat /tmp/c7check.json >> "$out"; done
  jq -c '{system, ok, mode, token_kid, expected_kid, pinned_kid, tokenreview_authenticated}' "$out"
}

[[ $# -ge 1 ]] || { sed -n '2,17p' "$0"; exit 2; }
source deploy/multihost/clock-check.sh
# shellcheck disable=SC2086
clock_check $ALL_HOSTS || die "clock check failed (N50)"
for s in "$@"; do
  case "$s" in
    all)
      step_build; step_nodes; step_cluster; step_coord; step_lg; step_deploy t5
      [[ -f "$S7/topology-tsame.env" ]] && step_deploy tsame
      step_cp_tools; step_smoke ;;
    build) step_build;; nodes) step_nodes;; cluster) step_cluster;; coord) step_coord;; lg) step_lg;;
    deploy-t5) step_deploy t5;; deploy-tsame) step_deploy tsame;; cp-tools) step_cp_tools;; smoke) step_smoke;;
    *) die "unknown step $s";;
  esac
done

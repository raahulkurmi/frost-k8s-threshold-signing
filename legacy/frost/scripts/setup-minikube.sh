#!/bin/bash
set -e

echo "=== FROST K8s Setup Script ==="

PROXY_IP=$(docker inspect deploy-grpc-proxy-1 | grep '"IPAddress"' | tail -1 | grep -o '[0-9.]*')
echo "Proxy IP: $PROXY_IP"

# Socat bridge — with keepalive loop
echo "Creating persistent socat bridge..."
docker exec minikube bash -c "
mkdir -p /var/run/frost-k8s
rm -f /var/run/frost-k8s/signer.sock

# Start socat in loop so it restarts if it dies
nohup sh -c 'while true; do socat UNIX-LISTEN:/var/run/frost-k8s/signer.sock,fork,reuseaddr TCP:${PROXY_IP}:9090; rm -f /var/run/frost-k8s/signer.sock; sleep 1; done' > /var/log/socat.log 2>&1 &
"
sleep 3
docker exec minikube ls /var/run/frost-k8s/signer.sock
echo "Persistent socat bridge created"

# Patch apiserver
docker exec minikube sed -i '/--service-account-signing-key-file/d' /etc/kubernetes/manifests/kube-apiserver.yaml
docker exec minikube sed -i '/--service-account-key-file/d' /etc/kubernetes/manifests/kube-apiserver.yaml

docker exec minikube bash -c "grep -q 'service-account-signing-endpoint' /etc/kubernetes/manifests/kube-apiserver.yaml || sed -i '/--service-account-issuer/i\\    - --service-account-signing-endpoint=/var/run/frost-k8s/signer.sock' /etc/kubernetes/manifests/kube-apiserver.yaml"

docker exec minikube bash -c "grep -q 'frost-k8s' /etc/kubernetes/manifests/kube-apiserver.yaml || (sed -i '/    volumeMounts:/a\\    - mountPath: /var/run/frost-k8s\n      name: frost-k8s' /etc/kubernetes/manifests/kube-apiserver.yaml && sed -i '/  volumes:/a\\  - hostPath:\n      path: /var/run/frost-k8s\n      type: DirectoryOrCreate\n    name: frost-k8s' /etc/kubernetes/manifests/kube-apiserver.yaml)"

echo "Manifest patched"

echo "=== Waiting 60s for apiserver restart ==="
sleep 60
kubectl get pods -n kube-system | grep apiserver
echo "=== Setup Complete ==="

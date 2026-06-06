#!/bin/bash
set -e

echo "=== FROST K8s Setup Script ==="

# Step 1: Get proxy IP
PROXY_IP=$(docker inspect deploy-grpc-proxy-1 | grep '"IPAddress"' | tail -1 | grep -o '[0-9.]*')
echo "Proxy IP: $PROXY_IP"

# Step 2: Socat bridge
echo "Creating socat bridge..."
docker exec minikube bash -c "pkill socat 2>/dev/null; mkdir -p /var/run/frost-k8s; rm -f /var/run/frost-k8s/signer.sock; socat UNIX-LISTEN:/var/run/frost-k8s/signer.sock,fork,reuseaddr TCP:${PROXY_IP}:9090 &"
sleep 2

# Step 3: Verify socket exists
docker exec minikube ls /var/run/frost-k8s/signer.sock
echo "Socket created"

# Step 4: Backup original manifest
docker exec minikube cp /etc/kubernetes/manifests/kube-apiserver.yaml /etc/kubernetes/manifests/kube-apiserver.yaml.bak
echo "Manifest backed up"

# Step 5: Remove single key flags
docker exec minikube sed -i '/--service-account-signing-key-file/d' /etc/kubernetes/manifests/kube-apiserver.yaml
docker exec minikube sed -i '/--service-account-key-file/d' /etc/kubernetes/manifests/kube-apiserver.yaml

# Step 6: Add signing endpoint
docker exec minikube sed -i '/--service-account-issuer/i\    - --service-account-signing-endpoint=/var/run/frost-k8s/signer.sock' /etc/kubernetes/manifests/kube-apiserver.yaml

# Step 7: Add volume mount
docker exec minikube sed -i '/    volumeMounts:/a\    - mountPath: /var/run/frost-k8s\n      name: frost-k8s' /etc/kubernetes/manifests/kube-apiserver.yaml

# Step 8: Add volume
docker exec minikube sed -i '/  volumes:/a\  - hostPath:\n      path: /var/run/frost-k8s\n      type: DirectoryOrCreate\n    name: frost-k8s' /etc/kubernetes/manifests/kube-apiserver.yaml

echo "Manifest patched"

# Step 9: Verify manifest is valid
echo "Checking manifest..."
docker exec minikube grep "signing-endpoint" /etc/kubernetes/manifests/kube-apiserver.yaml
docker exec minikube grep "frost-k8s" /etc/kubernetes/manifests/kube-apiserver.yaml | head -5

echo "=== Waiting 60s for apiserver restart ==="
sleep 60

# Step 10: Check apiserver
kubectl get pods -n kube-system | grep apiserver

echo "=== Setup Complete ==="

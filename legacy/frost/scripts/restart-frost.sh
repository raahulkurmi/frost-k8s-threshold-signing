#!/bin/bash
# restart-frost.sh — Run this after every minikube restart
# Updated: Uses coordinator-lb (nginx HA) instead of grpc-proxy inside minikube
set -e

echo "=== FROST K8s Restart Script ==="

# Step 1: Make sure deploy containers are running
echo "Starting deploy containers..."
cd "$(dirname "$0")/../deploy"
docker compose up -d
sleep 5
cd - > /dev/null

# Step 2: Get coordinator-lb IP
echo "Getting coordinator-lb IP..."
LB_IP=$(docker inspect deploy-coordinator-lb-1 | grep '"IPAddress"' | tail -1 | grep -o '[0-9.]*')
echo "Coordinator LB IP: $LB_IP"

if [ -z "$LB_IP" ]; then
  echo "ERROR: coordinator-lb IP not found"
  exit 1
fi

# Step 3: Copy files to minikube
echo "Copying certs and keys to minikube..."
docker exec minikube mkdir -p /app/data /app/certs /var/run/frost-k8s
docker cp data/frost-keys.json minikube:/app/data/frost-keys.json
docker cp data/ecdsa-signing.pem minikube:/app/data/ecdsa-signing.pem
docker cp certs/proxy.crt minikube:/app/certs/proxy.crt
docker cp certs/proxy.key minikube:/app/certs/proxy.key
docker cp certs/ca.crt minikube:/app/certs/ca.crt

# Step 4: Start socat bridge inside minikube
echo "Starting socat bridge → coordinator-lb:9090..."
docker exec minikube bash -c "
pkill socat 2>/dev/null
rm -f /var/run/frost-k8s/signer.sock
socat UNIX-LISTEN:/var/run/frost-k8s/signer.sock,fork,reuseaddr TCP:${LB_IP}:9090 &
sleep 2
ss -xlp | grep signer.sock
"

# Step 5: Patch kube-apiserver manifest
echo "Patching kube-apiserver..."
docker exec minikube bash -c "cat > /etc/kubernetes/manifests/kube-apiserver.yaml << 'ENDOFYAML'
apiVersion: v1
kind: Pod
metadata:
  labels:
    component: kube-apiserver
    tier: control-plane
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
  - command:
    - kube-apiserver
    - --advertise-address=192.168.49.2
    - --allow-privileged=true
    - --authorization-mode=Node,RBAC
    - --client-ca-file=/var/lib/minikube/certs/ca.crt
    - --enable-bootstrap-token-auth=true
    - --etcd-cafile=/var/lib/minikube/certs/etcd/ca.crt
    - --etcd-certfile=/var/lib/minikube/certs/apiserver-etcd-client.crt
    - --etcd-keyfile=/var/lib/minikube/certs/apiserver-etcd-client.key
    - --etcd-servers=https://127.0.0.1:2379
    - --kubelet-client-certificate=/var/lib/minikube/certs/apiserver-kubelet-client.crt
    - --kubelet-client-key=/var/lib/minikube/certs/apiserver-kubelet-client.key
    - --kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname
    - --proxy-client-cert-file=/var/lib/minikube/certs/front-proxy-client.crt
    - --proxy-client-key-file=/var/lib/minikube/certs/front-proxy-client.key
    - --requestheader-allowed-names=front-proxy-client
    - --requestheader-client-ca-file=/var/lib/minikube/certs/front-proxy-ca.crt
    - --requestheader-extra-headers-prefix=X-Remote-Extra-
    - --requestheader-group-headers=X-Remote-Group
    - --requestheader-username-headers=X-Remote-User
    - --secure-port=8443
    - --service-account-issuer=https://kubernetes.default.svc.cluster.local
    - --service-account-signing-endpoint=/var/run/frost-k8s/signer.sock
    - --service-cluster-ip-range=10.96.0.0/12
    - --tls-cert-file=/var/lib/minikube/certs/apiserver.crt
    - --tls-private-key-file=/var/lib/minikube/certs/apiserver.key
    - --enable-admission-plugins=NamespaceLifecycle,LimitRanger,ServiceAccount,DefaultStorageClass,DefaultTolerationSeconds,NodeRestriction,MutatingAdmissionWebhook,ValidatingAdmissionWebhook,ResourceQuota
    image: registry.k8s.io/kube-apiserver:v1.35.1
    imagePullPolicy: IfNotPresent
    name: kube-apiserver
    volumeMounts:
    - mountPath: /etc/ssl/certs
      name: ca-certs
      readOnly: true
    - mountPath: /etc/ca-certificates
      name: etc-ca-certificates
      readOnly: true
    - mountPath: /var/lib/minikube/certs
      name: k8s-certs
      readOnly: true
    - mountPath: /usr/local/share/ca-certificates
      name: usr-local-share-ca-certificates
      readOnly: true
    - mountPath: /usr/share/ca-certificates
      name: usr-share-ca-certificates
      readOnly: true
    - mountPath: /var/run/frost-k8s
      name: frost-k8s
  hostNetwork: true
  priorityClassName: system-node-critical
  volumes:
  - hostPath:
      path: /etc/ssl/certs
      type: DirectoryOrCreate
    name: ca-certs
  - hostPath:
      path: /etc/ca-certificates
      type: DirectoryOrCreate
    name: etc-ca-certificates
  - hostPath:
      path: /var/lib/minikube/certs
      type: DirectoryOrCreate
    name: k8s-certs
  - hostPath:
      path: /usr/local/share/ca-certificates
      type: DirectoryOrCreate
    name: usr-local-share-ca-certificates
  - hostPath:
      path: /usr/share/ca-certificates
      type: DirectoryOrCreate
    name: usr-share-ca-certificates
  - hostPath:
      path: /var/run/frost-k8s
      type: DirectoryOrCreate
    name: frost-k8s
status: {}
ENDOFYAML"

# Step 6: Wait and test
echo "Waiting 60s for apiserver restart..."
sleep 60

echo "=== Testing FROST signing ==="
HEADER=$(kubectl create token default | cut -d. -f1 | base64 -d 2>/dev/null)
echo "JWT Header: $HEADER"
if echo "$HEADER" | grep -q "frost-k8s-v1"; then
  echo "✅ FROST signing working!"
else
  echo "❌ FROST signing NOT working — check logs"
  docker exec minikube bash -c "cat /var/log/grpc-proxy-err.log 2>/dev/null"
fi

echo "=== Setup Complete ==="
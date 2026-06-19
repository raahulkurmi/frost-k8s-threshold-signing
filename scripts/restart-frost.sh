#!/bin/bash
# restart-frost.sh — Run this after every minikube restart
set -e

echo "=== FROST K8s Restart Script ==="

# Step 1: Get signer IPs
echo "Getting signer IPs..."
S1=$(docker inspect deploy-signer-1-1 | grep '"IPAddress"' | tail -1 | grep -o '[0-9.]*')
S2=$(docker inspect deploy-signer-2-1 | grep '"IPAddress"' | tail -1 | grep -o '[0-9.]*')
S3=$(docker inspect deploy-signer-3-1 | grep '"IPAddress"' | tail -1 | grep -o '[0-9.]*')
S4=$(docker inspect deploy-signer-4-1 | grep '"IPAddress"' | tail -1 | grep -o '[0-9.]*')
S5=$(docker inspect deploy-signer-5-1 | grep '"IPAddress"' | tail -1 | grep -o '[0-9.]*')

echo "Signer IPs: $S1 $S2 $S3 $S4 $S5"

# Step 2: Copy files to minikube
echo "Copying files to minikube..."
docker exec minikube mkdir -p /app/data /app/certs /var/run/frost-k8s
docker cp data/frost-keys.json minikube:/app/data/frost-keys.json
docker cp data/ecdsa-signing.pem minikube:/app/data/ecdsa-signing.pem
docker cp certs/proxy.crt minikube:/app/certs/proxy.crt
docker cp certs/proxy.key minikube:/app/certs/proxy.key
docker cp certs/ca.crt minikube:/app/certs/ca.crt

# Step 3: Build and copy grpc-proxy binary
echo "Building grpc-proxy (ARM64)..."
GOOS=linux GOARCH=arm64 go build -o /tmp/grpc-proxy-arm64 ./cmd/grpc-proxy/
docker cp /tmp/grpc-proxy-arm64 minikube:/usr/local/bin/grpc-proxy
docker exec minikube chmod +x /usr/local/bin/grpc-proxy

# Step 4: Start grpc-proxy inside minikube
echo "Starting grpc-proxy inside minikube..."
docker exec minikube bash -c "
pkill grpc-proxy 2>/dev/null
pkill socat 2>/dev/null
rm -f /var/run/frost-k8s/signer.sock
cd /app && nohup env \
  SIGNER_1_ADDR=https://${S1}:8081 \
  SIGNER_2_ADDR=https://${S2}:8082 \
  SIGNER_3_ADDR=https://${S3}:8083 \
  SIGNER_4_ADDR=https://${S4}:8084 \
  SIGNER_5_ADDR=https://${S5}:8085 \
  SOCKET_PATH=/var/run/frost-k8s/signer.sock \
  KEY_ID=frost-k8s-v1 \
  ECDSA_KEY_PATH=/app/data/ecdsa-signing.pem \
  TLS_CERT=/app/certs/proxy.crt \
  TLS_KEY=/app/certs/proxy.key \
  TLS_CA=/app/certs/ca.crt \
  /usr/local/bin/grpc-proxy > /var/log/grpc-proxy.log 2>/var/log/grpc-proxy-err.log &
sleep 2
cat /var/log/grpc-proxy.log
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
kubectl create token default | cut -d. -f1 | base64 -d
echo ""
echo "=== Setup Complete ==="

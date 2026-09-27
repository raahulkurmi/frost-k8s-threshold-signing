package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A kube-apiserver manifest shaped like kubeadm v1.36 output (flags in
// command, hostPath volumes, probes), with the TokenRequest audit flags 7C adds
// at kubeadm init.
const apiserverYAML = `apiVersion: v1
kind: Pod
metadata:
  annotations:
    kubeadm.kubernetes.io/kube-apiserver.advertise-address.endpoint: 172.31.0.10:6443
  labels:
    component: kube-apiserver
    tier: control-plane
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
  - command:
    - kube-apiserver
    - --advertise-address=172.31.0.10
    - --audit-log-path=/var/log/kubernetes/audit.log
    - --audit-policy-file=/etc/kubernetes/audit/audit-policy.yaml
    - --authorization-mode=Node,RBAC
    - --service-account-issuer=https://kubernetes.default.svc.cluster.local
    - --service-account-key-file=/etc/kubernetes/pki/sa.pub
    - --service-account-signing-key-file=/etc/kubernetes/pki/sa.key
    - --tls-private-key-file=/etc/kubernetes/pki/apiserver.key
    image: registry.k8s.io/kube-apiserver:v1.36.5
    imagePullPolicy: IfNotPresent
    livenessProbe:
      failureThreshold: 8
      httpGet:
        host: 172.31.0.10
        path: /livez
        port: 6443
        scheme: HTTPS
      initialDelaySeconds: 10
      periodSeconds: 10
      timeoutSeconds: 15
    name: kube-apiserver
    resources:
      requests:
        cpu: 250m
    volumeMounts:
    - mountPath: /etc/kubernetes/pki
      name: k8s-certs
      readOnly: true
  hostNetwork: true
  priority: 2000001000
  priorityClassName: system-node-critical
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  volumes:
  - hostPath:
      path: /etc/kubernetes/pki
      type: DirectoryOrCreate
    name: k8s-certs
status: {}
`

const kcmYAML = `apiVersion: v1
kind: Pod
metadata:
  name: kube-controller-manager
  namespace: kube-system
spec:
  containers:
  - command:
    - kube-controller-manager
    - --root-ca-file=/etc/kubernetes/pki/ca.crt
    - --service-account-private-key-file=/etc/kubernetes/pki/sa.key
    - --use-service-account-credentials=true
    image: registry.k8s.io/kube-controller-manager:v1.36.5
    name: kube-controller-manager
  hostNetwork: true
status: {}
`

func write(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExternalAPIServerRoundTrip(t *testing.T) {
	in := write(t, "kube-apiserver.yaml", apiserverYAML)
	p, err := readPod(in)
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := Mode(p); m != "in-tree" {
		t.Fatalf("pristine mode %q, want in-tree", m)
	}
	out := filepath.Join(t.TempDir(), "ext.yaml")
	if err := run([]string{"external-apiserver", in, out}); err != nil {
		t.Fatal(err)
	}
	q, err := readPod(out)
	if err != nil {
		t.Fatal(err)
	}
	fs := q.Spec.Containers[0].Command
	if m, _ := Mode(q); m != "external" {
		t.Fatalf("rewritten mode %q, want external; flags %v", m, fs)
	}
	for _, gone := range []string{"--service-account-key-file", "--service-account-signing-key-file"} {
		if hasFlag(fs, gone) {
			t.Fatalf("%s still present", gone)
		}
	}
	// Every other flag is kept, in order, and the binary name stays first.
	want := []string{"kube-apiserver", "--advertise-address=172.31.0.10", "--audit-log-path=/var/log/kubernetes/audit.log",
		"--audit-policy-file=/etc/kubernetes/audit/audit-policy.yaml", "--authorization-mode=Node,RBAC",
		"--service-account-issuer=https://kubernetes.default.svc.cluster.local", "--tls-private-key-file=/etc/kubernetes/pki/apiserver.key",
		"--service-account-signing-endpoint=" + SocketPath}
	if !slices.Equal(fs, want) {
		t.Fatalf("flags\n got %v\nwant %v", fs, want)
	}
	if n := len(q.Spec.Volumes); n != 2 || q.Spec.Volumes[1].HostPath.Path != SocketDir || *q.Spec.Volumes[1].HostPath.Type != "Directory" {
		t.Fatalf("socket volume not added: %+v", q.Spec.Volumes)
	}
	if m := q.Spec.Containers[0].VolumeMounts; len(m) != 2 || m[1].MountPath != SocketDir {
		t.Fatalf("socket mount not added: %+v", m)
	}
	if q.Spec.Containers[0].LivenessProbe == nil || !q.Spec.HostNetwork || q.Spec.PriorityClassName != "system-node-critical" {
		t.Fatal("unrelated pod fields lost in the round trip")
	}
	// Applying it again to the external manifest is refused (not in-tree input).
	if err := run([]string{"external-apiserver", out, out + ".2"}); err == nil || !strings.Contains(err.Error(), "not an in-tree") {
		t.Fatalf("second rewrite: %v", err)
	}
}

func TestModeMixed(t *testing.T) {
	p, _ := readPod(write(t, "a.yaml", apiserverYAML))
	c := &p.Spec.Containers[0]
	c.Command = append(c.Command, "--service-account-signing-endpoint="+SocketPath) // both key and endpoint
	if m, _ := Mode(p); m != "mixed" {
		t.Fatalf("mode %q, want mixed", m)
	}
	p, _ = readPod(write(t, "b.yaml", apiserverYAML))
	c = &p.Spec.Containers[0]
	c.Command = dropFlag(c.Command, "--service-account-signing-key-file") // neither
	if m, _ := Mode(p); m != "mixed" {
		t.Fatalf("mode %q, want mixed", m)
	}
}

func TestExternalKCM(t *testing.T) {
	in := write(t, "kcm.yaml", kcmYAML)
	out := filepath.Join(t.TempDir(), "kcm-ext.yaml")
	if err := run([]string{"external-kcm", in, out}); err != nil {
		t.Fatal(err)
	}
	q, _ := readPod(out)
	want := []string{"kube-controller-manager", "--root-ca-file=/etc/kubernetes/pki/ca.crt", "--use-service-account-credentials=true"}
	if !slices.Equal(q.Spec.Containers[0].Command, want) {
		t.Fatalf("flags %v, want %v", q.Spec.Containers[0].Command, want)
	}
}

func TestKID(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	got, err := KID(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	if want := base64.RawURLEncoding.EncodeToString(sum[:]); got != want || len(got) != 43 {
		t.Fatalf("kid %q, want %q (43 chars)", got, want)
	}
	if _, err := KID([]byte("not pem")); err == nil {
		t.Fatal("accepted non-PEM input")
	}
}

func TestStamp(t *testing.T) {
	in := write(t, "kcm.yaml", kcmYAML)
	out := filepath.Join(t.TempDir(), "s.yaml")
	if err := run([]string{"stamp", in, out, "T-5region-optimistic-20260927T100000Z"}); err != nil {
		t.Fatal(err)
	}
	q, _ := readPod(out)
	if q.Annotations[StampKey] != "T-5region-optimistic-20260927T100000Z" || len(q.Spec.Containers[0].Command) != 4 {
		t.Fatalf("stamp: annotations %v, command %v", q.Annotations, q.Spec.Containers[0].Command)
	}
}

func TestReadPodRejectsUnknownFields(t *testing.T) {
	if _, err := readPod(write(t, "bad.yaml", apiserverYAML+"bogusTopLevel: 1\n")); err == nil {
		t.Fatal("unknown field accepted")
	}
}

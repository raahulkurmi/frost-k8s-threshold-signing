// Command k8s7c edits kubeadm static-pod manifests for Phase 7C, where one
// kubeadm cluster is switched between B0 (in-tree service account key) and the
// external signer (B1 / T) by rewriting kube-apiserver and
// kube-controller-manager manifests (NOTES N67). BENCHMARK TOOLING ONLY.
//
//	k8s7c external-apiserver IN OUT   in-tree kube-apiserver manifest -> external signer
//	k8s7c external-kcm IN OUT         drop --service-account-private-key-file (legacy token controller)
//	k8s7c mode MANIFEST               print in-tree | external | mixed for a kube-apiserver manifest
//	k8s7c kid PUBKEY.pem              kid kube-apiserver derives for an in-tree public key
//	k8s7c stamp IN OUT VALUE          set annotation frost-7c/switch=VALUE (forces kubelet to
//	                                  restart the static pod: the apiserver refetches the
//	                                  external signer's keys at startup, and the controller-
//	                                  manager drops tokens cached from the previous signer)
//
// The external variant is derived from kubeadm's pristine in-tree manifest, so
// switching back is copying the pristine file. Flags are edited on the typed
// Pod (command and args), never as text.
package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

const (
	SocketDir  = "/var/run/frost-k8s"
	SocketPath = SocketDir + "/signer.sock"
	volName    = "frost-socket"
	StampKey   = "frost-7c/switch"
)

// Stamp sets the switch annotation.
func Stamp(p *corev1.Pod, value string) {
	if p.Annotations == nil {
		p.Annotations = map[string]string{}
	}
	p.Annotations[StampKey] = value
}

// flags returns a pointer to the slice holding the container's flags: kubeadm
// puts them in command (after the binary name); args is used if non-empty.
func flags(c *corev1.Container) *[]string {
	if len(c.Args) > 0 {
		return &c.Args
	}
	return &c.Command
}

func container(p *corev1.Pod, name string) (*corev1.Container, error) {
	for i := range p.Spec.Containers {
		if p.Spec.Containers[i].Name == name {
			return &p.Spec.Containers[i], nil
		}
	}
	return nil, fmt.Errorf("no container %q in %s", name, p.Name)
}

func hasFlag(fs []string, name string) bool {
	return slices.ContainsFunc(fs, func(f string) bool { return f == name || strings.HasPrefix(f, name+"=") })
}

func dropFlag(fs []string, name string) []string {
	return slices.DeleteFunc(fs, func(f string) bool { return f == name || strings.HasPrefix(f, name+"=") })
}

// ExternalAPIServer rewrites an in-tree kube-apiserver pod to sign only via the
// external signer socket: the two in-tree key flags are removed (they are
// mutually exclusive with the endpoint), the endpoint flag and a hostPath mount
// of the socket directory are added. The issuer must already be set.
func ExternalAPIServer(p *corev1.Pod) error {
	c, err := container(p, "kube-apiserver")
	if err != nil {
		return err
	}
	fs := flags(c)
	if !hasFlag(*fs, "--service-account-issuer") {
		return errors.New("kube-apiserver has no --service-account-issuer")
	}
	if !hasFlag(*fs, "--service-account-signing-key-file") {
		return errors.New("input is not an in-tree manifest (no --service-account-signing-key-file)")
	}
	*fs = dropFlag(*fs, "--service-account-key-file")
	*fs = dropFlag(*fs, "--service-account-signing-key-file")
	*fs = dropFlag(*fs, "--service-account-signing-endpoint")
	*fs = append(*fs, "--service-account-signing-endpoint="+SocketPath)
	dir := corev1.HostPathDirectory
	p.Spec.Volumes = slices.DeleteFunc(p.Spec.Volumes, func(v corev1.Volume) bool { return v.Name == volName })
	p.Spec.Volumes = append(p.Spec.Volumes, corev1.Volume{Name: volName,
		VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: SocketDir, Type: &dir}}})
	c.VolumeMounts = slices.DeleteFunc(c.VolumeMounts, func(m corev1.VolumeMount) bool { return m.Name == volName })
	c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: volName, MountPath: SocketDir})
	return nil
}

// ExternalKCM removes the legacy token controller's private key flag.
func ExternalKCM(p *corev1.Pod) error {
	c, err := container(p, "kube-controller-manager")
	if err != nil {
		return err
	}
	fs := flags(c)
	*fs = dropFlag(*fs, "--service-account-private-key-file")
	return nil
}

// Mode classifies a kube-apiserver pod.
func Mode(p *corev1.Pod) (string, error) {
	c, err := container(p, "kube-apiserver")
	if err != nil {
		return "", err
	}
	fs := *flags(c)
	ext := slices.Contains(fs, "--service-account-signing-endpoint="+SocketPath)
	keys := hasFlag(fs, "--service-account-signing-key-file") || hasFlag(fs, "--service-account-key-file")
	switch {
	case ext && !keys:
		return "external", nil
	case !ext && hasFlag(fs, "--service-account-signing-key-file") && !hasFlag(fs, "--service-account-signing-endpoint"):
		return "in-tree", nil
	}
	return "mixed", nil
}

// KID is kube-apiserver's key ID for an in-tree key: base64url(SHA-256(PKIX DER)).
func KID(pemBytes []byte) (string, error) {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return "", errors.New("no PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func readPod(path string) (*corev1.Pod, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p corev1.Pod
	if err := yaml.UnmarshalStrict(b, &p); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &p, nil
}

func writePod(path string, p *corev1.Pod) error {
	b, err := yaml.Marshal(p)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func run(args []string) error {
	if len(args) < 2 {
		return errors.New("usage: k8s7c external-apiserver|external-kcm IN OUT | mode MANIFEST | kid PUBKEY.pem")
	}
	switch args[0] {
	case "external-apiserver", "external-kcm":
		if len(args) != 3 {
			return errors.New("usage: k8s7c " + args[0] + " IN OUT")
		}
		p, err := readPod(args[1])
		if err != nil {
			return err
		}
		if args[0] == "external-apiserver" {
			err = ExternalAPIServer(p)
		} else {
			err = ExternalKCM(p)
		}
		if err != nil {
			return err
		}
		return writePod(args[2], p)
	case "stamp":
		if len(args) != 4 {
			return errors.New("usage: k8s7c stamp IN OUT VALUE")
		}
		p, err := readPod(args[1])
		if err != nil {
			return err
		}
		Stamp(p, args[3])
		return writePod(args[2], p)
	case "mode":
		p, err := readPod(args[1])
		if err != nil {
			return err
		}
		m, err := Mode(p)
		if err != nil {
			return err
		}
		fmt.Println(m)
		return nil
	case "kid":
		b, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		k, err := KID(b)
		if err != nil {
			return err
		}
		fmt.Println(k)
		return nil
	}
	return fmt.Errorf("unknown subcommand %q", args[0])
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "k8s7c:", err)
		os.Exit(1)
	}
}

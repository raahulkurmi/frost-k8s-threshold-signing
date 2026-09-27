// Package tlsconf builds the mutually authenticated TLS configurations
// between the coordinator and the signers. Identities are DNS SANs issued by
// scripts/gen-certs.sh: "coordinator-<k>" (clientAuth, one per coordinator
// replica, NOTES N76) and "signer-<i>" (serverAuth).
package tlsconf

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// MaxCoordinators bounds coordinator replica ids (coordinator-1..64).
const MaxCoordinators = 64

// CoordinatorName returns replica k's client identity, coordinator-<k>. Each
// replica has its own certificate, so a signer can tell replicas apart and
// give each a fair share under overload (N76).
func CoordinatorName(k int) string { return fmt.Sprintf("coordinator-%d", k) }

// CoordinatorID parses a coordinator client identity. Only the canonical
// form coordinator-<k> with k in [1, MaxCoordinators] is accepted.
func CoordinatorID(san string) (int, bool) {
	rest, ok := strings.CutPrefix(san, "coordinator-")
	if !ok || rest == "" || len(rest) > 2 || rest[0] == '0' {
		return 0, false
	}
	k, err := strconv.Atoi(rest)
	if err != nil || k < 1 || k > MaxCoordinators || strconv.Itoa(k) != rest {
		return 0, false
	}
	return k, true
}

// coordinatorSAN checks that cert has exactly one DNS SAN, a coordinator
// identity, and no other SAN types.
func coordinatorSAN(cert *x509.Certificate) error {
	if len(cert.DNSNames) == 1 && len(cert.IPAddresses) == 0 && len(cert.EmailAddresses) == 0 && len(cert.URIs) == 0 {
		if _, ok := CoordinatorID(cert.DNSNames[0]); ok {
			return nil
		}
	}
	return fmt.Errorf("certificate SANs %v (ip %v) are not exactly one DNS:coordinator-<1..%d>", cert.DNSNames, cert.IPAddresses, MaxCoordinators)
}

// SignerName returns the identity of signer i.
func SignerName(i int) string { return fmt.Sprintf("signer-%d", i) }

// exactlyOneSAN reports whether cert has exactly one DNS SAN equal to want and
// no other SAN types.
func exactlyOneSAN(cert *x509.Certificate, want string) error {
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != want ||
		len(cert.IPAddresses) != 0 || len(cert.EmailAddresses) != 0 || len(cert.URIs) != 0 {
		return fmt.Errorf("certificate SANs %v (ip %v) are not exactly DNS:%s", cert.DNSNames, cert.IPAddresses, want)
	}
	return nil
}

func loadPool(caFile string) (*x509.CertPool, error) {
	if caFile == "" {
		return nil, errors.New("tls: CA file path is empty")
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("tls: read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("tls: %s contains no certificates", caFile)
	}
	return pool, nil
}

func loadLeaf(certFile, keyFile, want string) (tls.Certificate, error) {
	if certFile == "" || keyFile == "" {
		return tls.Certificate{}, errors.New("tls: cert and key paths are required")
	}
	c, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tls: load %s: %w", certFile, err)
	}
	if err := exactlyOneSAN(c.Leaf, want); err != nil {
		return tls.Certificate{}, fmt.Errorf("tls: own certificate %s: %w", certFile, err)
	}
	return c, nil
}

// SignerServer returns the TLS config for signer i: its own cert must be
// exactly DNS:signer-<i>; clients must present a cert chaining to caFile with
// exactly one DNS:coordinator-<k> and clientAuth EKU. TLS 1.3 only.
func SignerServer(certFile, keyFile, caFile string, i int) (*tls.Config, error) {
	own, err := loadLeaf(certFile, keyFile, SignerName(i))
	if err != nil {
		return nil, err
	}
	pool, err := loadPool(caFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{own},
		ClientAuth:   tls.RequireAndVerifyClientCert, // chain + clientAuth EKU verified by crypto/tls
		ClientCAs:    pool,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no client certificate")
			}
			return coordinatorSAN(cs.PeerCertificates[0])
		},
	}, nil
}

// CoordinatorClient returns the TLS config coordinator replica coordID uses to
// reach signer i: its own cert must be exactly DNS:coordinator-<coordID>; the server must
// present a cert chaining to caFile with exactly DNS:signer-<i>, regardless of
// the endpoint's host name or IP.
func CoordinatorClient(certFile, keyFile, caFile string, i, coordID int) (*tls.Config, error) {
	if coordID < 1 || coordID > MaxCoordinators {
		return nil, fmt.Errorf("tls: coordinator id %d outside [1,%d]", coordID, MaxCoordinators)
	}
	own, err := loadLeaf(certFile, keyFile, CoordinatorName(coordID))
	if err != nil {
		return nil, err
	}
	pool, err := loadPool(caFile)
	if err != nil {
		return nil, err
	}
	want := SignerName(i)
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{own},
		RootCAs:      pool,
		ServerName:   want, // hostname verification against the signer identity
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no server certificate")
			}
			return exactlyOneSAN(cs.PeerCertificates[0], want)
		},
	}, nil
}

// LBName is the only client identity a coordinator's TCP gRPC listener
// accepts: the nginx load balancer in front of the coordinators.
const LBName = "lb"

// CoordinatorGRPCName is the server identity of a coordinator's TCP gRPC
// listener, verified by nginx (grpc_ssl_name).
const CoordinatorGRPCName = "coordinator-grpc"

// CoordinatorGRPCServer returns the TLS config for a coordinator's TCP gRPC
// listener: its own cert must be exactly DNS:coordinator-grpc; clients must
// present a cert chaining to caFile with exactly DNS:lb and clientAuth EKU.
// A Unix-socket listener (kube-apiserver dialling locally) does not use TLS.
func CoordinatorGRPCServer(certFile, keyFile, caFile string) (*tls.Config, error) {
	own, err := loadLeaf(certFile, keyFile, CoordinatorGRPCName)
	if err != nil {
		return nil, err
	}
	pool, err := loadPool(caFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{own},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		NextProtos:   []string{"h2"},
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no client certificate")
			}
			return exactlyOneSAN(cs.PeerCertificates[0], LBName)
		},
	}, nil
}

// Package tlsconf builds the mutually authenticated TLS configurations
// between the coordinator and the signers. Identities are DNS SANs issued by
// scripts/gen-certs.sh: "coordinator" (clientAuth) and "signer-<i>" (serverAuth).
package tlsconf

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// CoordinatorName is the only client identity signers accept.
const CoordinatorName = "coordinator"

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
// exactly DNS:coordinator and clientAuth EKU. TLS 1.3 only.
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
			return exactlyOneSAN(cs.PeerCertificates[0], CoordinatorName)
		},
	}, nil
}

// CoordinatorClient returns the TLS config the coordinator uses to reach
// signer i: its own cert must be exactly DNS:coordinator; the server must
// present a cert chaining to caFile with exactly DNS:signer-<i>, regardless of
// the endpoint's host name or IP.
func CoordinatorClient(certFile, keyFile, caFile string, i int) (*tls.Config, error) {
	own, err := loadLeaf(certFile, keyFile, CoordinatorName)
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

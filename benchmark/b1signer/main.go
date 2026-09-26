// Command b1signer is the Phase 7A **B1 baseline**: a single-key RS256
// ExternalJWTSigner. BENCHMARK ONLY. It lives in the separate benchmark
// module, is never part of the threshold images or compose files, and nothing
// in the threshold system can reach it (NOTES N54). It exists so that B1 vs T
// isolates the cost of threshold signing: B1 runs in the coordinators' place
// behind the same nginx and unix socket, with the same gRPC server
// (internal/grpcserver), the same mTLS (tlsconf.CoordinatorGRPCServer), the same
// JWT header and claims-segment checks (internal/jwtfmt), and the same 3
// replicas. The only difference: it signs locally with one RSA-2048 key instead
// of fanning out to 5 signers and combining 3 shares.
//
// Environment:
//
//	B1_KEY_FILE      PKCS#8 PEM RSA private key (generated per benchmark run, wiped after)
//	POLICY_FILE      the signers' policy (only max_token_expiration_seconds is used, as grpc-proxy does)
//	TCP_ADDR         listen address, e.g. 0.0.0.0:9090
//	GRPC_TLS_CERT, GRPC_TLS_KEY, GRPC_TLS_CA   server cert with SAN coordinator-grpc; client must be "lb"
package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"frost-k8s-threshold-signing/internal/coordinator"
	"frost-k8s-threshold-signing/internal/grpcserver"
	"frost-k8s-threshold-signing/internal/jwtfmt"
	"frost-k8s-threshold-signing/internal/keymeta"
	"frost-k8s-threshold-signing/internal/policy"
	"frost-k8s-threshold-signing/internal/tlsconf"
)

// singleKey signs header.claims with one RSA key (RSASSA-PKCS1-v1_5, SHA-256).
type singleKey struct {
	key       *rsa.PrivateKey
	headerSeg string
}

func (s *singleKey) Sign(_ context.Context, claims string) (*coordinator.Result, error) {
	if err := jwtfmt.CheckSegment(claims); err != nil {
		return nil, fmt.Errorf("%w: %v", coordinator.ErrInvalidClaims, err)
	}
	input := s.headerSeg + "." + claims
	if len(input) > jwtfmt.MaxSigningInput {
		return nil, fmt.Errorf("%w: too large", coordinator.ErrInvalidClaims)
	}
	d := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, d[:])
	if err != nil {
		return nil, err
	}
	return &coordinator.Result{Header: s.headerSeg, Signature: base64.RawURLEncoding.EncodeToString(sig)}, nil
}

func loadKey(path string) (*rsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("B1_KEY_FILE: no PEM block")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok || rk.N.BitLen() != 2048 {
		return nil, errors.New("B1_KEY_FILE: want an RSA-2048 key")
	}
	return rk, nil
}

// newServer builds the same grpcserver.Server the coordinator uses, backed by
// one key. The Meta carries only public data (KID, PKIX, public key).
func newServer(key *rsa.PrivateKey, maxToken int64, created time.Time) (*grpcserver.Server, *keymeta.Meta, error) {
	pkix, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	meta := &keymeta.Meta{KID: keymeta.ComputeKID(pkix), Threshold: 1, Parties: 1, ModulusBits: 2048,
		PKIX: pkix, PublicKey: &key.PublicKey, CreatedAt: created.UTC()}
	hdr, err := jwtfmt.EncodedHeader(meta.KID)
	if err != nil {
		return nil, nil, err
	}
	srv, err := grpcserver.New(&singleKey{key: key, headerSeg: hdr}, meta, maxToken, 3600)
	return srv, meta, err
}

func run() error {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	need := func(k string) (string, error) {
		if v := os.Getenv(k); v != "" {
			return v, nil
		}
		return "", fmt.Errorf("%s is required", k)
	}
	var vals [6]string
	for i, k := range []string{"B1_KEY_FILE", "POLICY_FILE", "TCP_ADDR", "GRPC_TLS_CERT", "GRPC_TLS_KEY", "GRPC_TLS_CA"} {
		v, err := need(k)
		if err != nil {
			return err
		}
		vals[i] = v
	}
	key, err := loadKey(vals[0])
	if err != nil {
		return err
	}
	pol, err := policy.Load(vals[1])
	if err != nil {
		return err
	}
	// The key file's mtime, so all 3 replicas report the same FetchKeys
	// data_timestamp (the threshold coordinators use public-meta's created_at).
	fi, err := os.Stat(vals[0])
	if err != nil {
		return err
	}
	srv, meta, err := newServer(key, pol.MaxTokenSeconds(), fi.ModTime())
	if err != nil {
		return err
	}
	tc, err := tlsconf.CoordinatorGRPCServer(vals[3], vals[4], vals[5])
	if err != nil {
		return err
	}
	lis, err := net.Listen("tcp", vals[2])
	if err != nil {
		return err
	}
	g := grpcserver.NewGRPC(srv, grpc.Creds(credentials.NewTLS(tc)))
	logger.Info("b1signer ready (BENCHMARK BASELINE: single key)", "kid", meta.KID, "listen", lis.Addr().String())
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); g.GracefulStop() }()
	return g.Serve(lis)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "b1signer:", err)
		os.Exit(1)
	}
}

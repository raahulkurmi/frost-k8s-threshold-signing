// Command grpc-proxy is the threshold coordinator: a Kubernetes
// ExternalJWTSigner (v1) that obtains RS256 signatures by combining >= t
// threshold RSA signature shares from independent signers. It holds no
// secret share and no private key (I3); only public metadata and its own
// mTLS client certificate.
//
// Environment (required unless noted; anything missing aborts startup):
//
//	META_FILE          public-meta.json
//	POLICY_FILE        the signers' claims policy (for max_token_expiration_seconds)
//	SIGNER_ENDPOINTS   "1=https://signer-1:8443,2=https://signer-2:8443,..." (>= t entries)
//	TLS_CERT, TLS_KEY  coordinator client cert (SAN exactly DNS:coordinator)
//	TLS_CA             CA that issued the signers' server certs
//	SOCKET_PATH | TCP_ADDR  exactly one listener
//	GRPC_TLS_CERT, GRPC_TLS_KEY, GRPC_TLS_CA  required with TCP_ADDR: the
//	                   listener is mTLS only (own SAN exactly DNS:coordinator-grpc,
//	                   clients must present SAN exactly DNS:lb). There is no
//	                   plaintext TCP mode. SOCKET_PATH (local) uses no TLS.
//	SIGN_DEADLINE      optional, Go duration, default 2s
//	VERIFY_STRATEGY    optional, strict (default) | optimistic
//	REFRESH_HINT_SECONDS optional, default 3600
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"frost-k8s-threshold-signing/internal/coordinator"
	"frost-k8s-threshold-signing/internal/grpcserver"
	"frost-k8s-threshold-signing/internal/keymeta"
	"frost-k8s-threshold-signing/internal/policy"
	"frost-k8s-threshold-signing/internal/tlsconf"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(context.Background(), os.Getenv, logger); err != nil {
		logger.Error("coordinator failed", "err", err.Error())
		os.Exit(1)
	}
}

type settings struct {
	Meta        *keymeta.Meta
	MaxToken    int64
	Endpoints   []coordinator.Endpoint
	Deadline    time.Duration
	Strategy    coordinator.Strategy
	RefreshHint int64
	Socket      string
	TCP         string
	GRPCCert    string
	GRPCKey     string
	GRPCCA      string
}

func require(getenv func(string) string, name string) (string, error) {
	if v := getenv(name); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("%s is not set", name)
}

// parseEndpoints parses "1=https://signer-1:8443,2=...".
func parseEndpoints(s string) (map[int]string, error) {
	out := map[int]string{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		idStr, url, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("SIGNER_ENDPOINTS entry %q is not id=url", part)
		}
		id, err := strconv.Atoi(idStr)
		if err != nil {
			return nil, fmt.Errorf("SIGNER_ENDPOINTS id %q is not an integer", idStr)
		}
		if _, dup := out[id]; dup {
			return nil, fmt.Errorf("SIGNER_ENDPOINTS lists signer %d twice", id)
		}
		if !strings.HasPrefix(url, "https://") {
			return nil, fmt.Errorf("SIGNER_ENDPOINTS signer %d url %q must be https://", id, url)
		}
		out[id] = url
	}
	if len(out) == 0 {
		return nil, errors.New("SIGNER_ENDPOINTS is empty")
	}
	return out, nil
}

func load(getenv func(string) string) (*settings, error) {
	var s settings
	metaPath, err := require(getenv, "META_FILE")
	if err != nil {
		return nil, err
	}
	if s.Meta, err = keymeta.Load(metaPath); err != nil {
		return nil, err
	}
	policyPath, err := require(getenv, "POLICY_FILE")
	if err != nil {
		return nil, err
	}
	pol, err := policy.Load(policyPath)
	if err != nil {
		return nil, err
	}
	s.MaxToken = pol.MaxTokenSeconds()

	epStr, err := require(getenv, "SIGNER_ENDPOINTS")
	if err != nil {
		return nil, err
	}
	eps, err := parseEndpoints(epStr)
	if err != nil {
		return nil, err
	}
	cert, err := require(getenv, "TLS_CERT")
	if err != nil {
		return nil, err
	}
	key, err := require(getenv, "TLS_KEY")
	if err != nil {
		return nil, err
	}
	ca, err := require(getenv, "TLS_CA")
	if err != nil {
		return nil, err
	}
	ids := make([]int, 0, len(eps))
	for id := range eps {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	for _, id := range ids {
		tc, err := tlsconf.CoordinatorClient(cert, key, ca, id)
		if err != nil {
			return nil, err
		}
		s.Endpoints = append(s.Endpoints, coordinator.Endpoint{
			ID:  id,
			URL: eps[id],
			Client: &http.Client{Transport: &http.Transport{
				TLSClientConfig:     tc,
				ForceAttemptHTTP2:   true,
				MaxIdleConnsPerHost: 64,
				IdleConnTimeout:     90 * time.Second,
				DialContext:         (&net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			}},
		})
	}

	s.Deadline = 2 * time.Second
	if v := getenv("SIGN_DEADLINE"); v != "" {
		if s.Deadline, err = time.ParseDuration(v); err != nil || s.Deadline <= 0 {
			return nil, fmt.Errorf("SIGN_DEADLINE %q is not a positive duration", v)
		}
	}
	s.Strategy = coordinator.Strict
	if v := getenv("VERIFY_STRATEGY"); v != "" {
		if s.Strategy, err = coordinator.ParseStrategy(v); err != nil {
			return nil, err
		}
	}
	s.RefreshHint = 3600
	if v := getenv("REFRESH_HINT_SECONDS"); v != "" {
		if s.RefreshHint, err = strconv.ParseInt(v, 10, 64); err != nil || s.RefreshHint <= 0 {
			return nil, fmt.Errorf("REFRESH_HINT_SECONDS %q must be a positive integer", v)
		}
	}
	s.Socket, s.TCP = getenv("SOCKET_PATH"), getenv("TCP_ADDR")
	if (s.Socket == "") == (s.TCP == "") {
		return nil, errors.New("set exactly one of SOCKET_PATH or TCP_ADDR")
	}
	if s.TCP != "" {
		for _, p := range []struct {
			dst  *string
			name string
		}{{&s.GRPCCert, "GRPC_TLS_CERT"}, {&s.GRPCKey, "GRPC_TLS_KEY"}, {&s.GRPCCA, "GRPC_TLS_CA"}} {
			if *p.dst, err = require(getenv, p.name); err != nil {
				return nil, fmt.Errorf("TCP_ADDR requires mTLS: %w", err)
			}
		}
	}
	return &s, nil
}

func run(ctx context.Context, getenv func(string) string, logger *slog.Logger) error {
	s, err := load(getenv)
	if err != nil {
		return err
	}
	coord, err := coordinator.New(coordinator.Config{Meta: s.Meta, Endpoints: s.Endpoints, Deadline: s.Deadline, Strategy: s.Strategy, Logger: logger})
	if err != nil {
		return err
	}
	srv, err := grpcserver.New(coord, s.Meta, s.MaxToken, s.RefreshHint)
	if err != nil {
		return err
	}
	var lis net.Listener
	var opts []grpc.ServerOption
	if s.Socket != "" {
		lis, err = grpcserver.ListenUnix(s.Socket)
	} else {
		tc, terr := tlsconf.CoordinatorGRPCServer(s.GRPCCert, s.GRPCKey, s.GRPCCA)
		if terr != nil {
			return terr
		}
		opts = append(opts, grpc.Creds(credentials.NewTLS(tc)))
		lis, err = net.Listen("tcp", s.TCP)
	}
	if err != nil {
		return err
	}
	g := grpcserver.NewGRPC(srv, opts...)
	ids := make([]int, len(s.Endpoints))
	for i, ep := range s.Endpoints {
		ids[i] = ep.ID
	}
	logger.Info("coordinator ready", "kid", s.Meta.KID, "threshold", s.Meta.Threshold, "parties", s.Meta.Parties,
		"signers", ids, "listen", lis.Addr().String(), "deadline", s.Deadline.String(), "strategy", s.Strategy,
		"max_token_seconds", s.MaxToken, "grpc_mtls", s.TCP != "")

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- g.Serve(lis) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		g.GracefulStop()
		return nil
	}
}

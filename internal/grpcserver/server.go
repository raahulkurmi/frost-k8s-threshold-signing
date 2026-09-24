// Package grpcserver serves the Kubernetes ExternalJWTSigner v1 API
// (k8s.io/externaljwt/apis/v1, byte-identical to kubernetes v1.36.5
// staging/src/k8s.io/externaljwt/apis/v1) on top of the threshold coordinator.
package grpcserver

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	externaljwtv1 "k8s.io/externaljwt/apis/v1"

	"frost-k8s-threshold-signing/internal/coordinator"
	"frost-k8s-threshold-signing/internal/keymeta"
	"frost-k8s-threshold-signing/internal/policy"
)

// Signer is the threshold signing backend.
type Signer interface {
	Sign(ctx context.Context, claims string) (*coordinator.Result, error)
}

// Server implements externaljwtv1.ExternalJWTSignerServer.
type Server struct {
	externaljwtv1.UnimplementedExternalJWTSignerServer
	signer          Signer
	meta            *keymeta.Meta
	maxTokenSeconds int64
	refreshHint     int64
}

// New validates its inputs. maxTokenSeconds must be the signers' policy max
// (policy.MinTokenSeconds <= x); refreshHint must be > 0 (api.proto).
func New(s Signer, meta *keymeta.Meta, maxTokenSeconds, refreshHint int64) (*Server, error) {
	switch {
	case s == nil || meta == nil:
		return nil, errors.New("grpcserver: signer and meta are required")
	case maxTokenSeconds < policy.MinTokenSeconds:
		return nil, fmt.Errorf("grpcserver: max_token_expiration_seconds %d < %d", maxTokenSeconds, policy.MinTokenSeconds)
	case refreshHint <= 0:
		return nil, errors.New("grpcserver: refresh_hint_seconds must be > 0")
	}
	return &Server{signer: s, meta: meta, maxTokenSeconds: maxTokenSeconds, refreshHint: refreshHint}, nil
}

// Generic errors returned to the caller (kube-apiserver, which relays them to
// the token requester). They deliberately carry no per-signer detail and no
// policy reason (NOTES.md N33): which rule refused a claim, and which signers
// are down, stay in the coordinator log and the signers' audit logs.
const (
	ErrMsgThreshold      = "token signing failed: threshold not met"
	ErrMsgInvalidRequest = "token signing failed: invalid request"
	ErrMsgInternal       = "token signing failed"
)

// Sign returns the base64url header and signature. On any failure it returns
// a gRPC error with a generic message and never a token.
func (s *Server) Sign(ctx context.Context, req *externaljwtv1.SignJWTRequest) (*externaljwtv1.SignJWTResponse, error) {
	if req.GetClaims() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMsgInvalidRequest)
	}
	res, err := s.signer.Sign(ctx, req.GetClaims())
	if err != nil {
		// The coordinator has already logged the detailed failure (per-signer
		// reasons, request_id); only the class of failure leaves this process.
		var te *coordinator.ThresholdError
		switch {
		case errors.As(err, &te):
			return nil, status.Error(codes.Unavailable, ErrMsgThreshold)
		case errors.Is(err, coordinator.ErrInvalidClaims):
			return nil, status.Error(codes.InvalidArgument, ErrMsgInvalidRequest)
		default:
			return nil, status.Error(codes.Internal, ErrMsgInternal)
		}
	}
	return &externaljwtv1.SignJWTResponse{Header: res.Header, Signature: res.Signature}, nil
}

// FetchKeys returns the threshold group public key. data_timestamp is the key
// ceremony time from public-meta.json, so every coordinator replica returns
// identical output (E8).
func (s *Server) FetchKeys(context.Context, *externaljwtv1.FetchKeysRequest) (*externaljwtv1.FetchKeysResponse, error) {
	return &externaljwtv1.FetchKeysResponse{
		Keys: []*externaljwtv1.Key{{
			KeyId:                    s.meta.KID,
			Key:                      s.meta.PKIX,
			ExcludeFromOidcDiscovery: false,
		}},
		DataTimestamp:      timestamppb.New(s.meta.CreatedAt),
		RefreshHintSeconds: s.refreshHint,
	}, nil
}

// Metadata reports the longest token lifetime the signers' policy allows.
func (s *Server) Metadata(context.Context, *externaljwtv1.MetadataRequest) (*externaljwtv1.MetadataResponse, error) {
	return &externaljwtv1.MetadataResponse{MaxTokenExpirationSeconds: s.maxTokenSeconds}, nil
}

// NewGRPC returns a grpc.Server with s registered.
func NewGRPC(s *Server, opts ...grpc.ServerOption) *grpc.Server {
	g := grpc.NewServer(opts...)
	externaljwtv1.RegisterExternalJWTSignerServer(g, s)
	return g
}

// ListenUnix listens on a Unix socket. A stale socket is removed; any other
// existing file at path is an error.
func ListenUnix(path string) (net.Listener, error) {
	if path == "" {
		return nil, errors.New("socket path is empty")
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&fs.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

package grpcserver

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "frost-k8s-threshold-signing/proto/externaljwt/v1alpha1"
)

type ThresholdSignFn func(payloadJSON []byte) (header, signature string, err error)

type Server struct {
	pb.UnimplementedExternalJWTSignerServer
	signFn              ThresholdSignFn
	keyID               string
	verificationKeyPKIX []byte
}

func New(signFn ThresholdSignFn, keyID string, verificationKeyPKIX []byte) (*Server, error) {
	return &Server{
		signFn:              signFn,
		keyID:               keyID,
		verificationKeyPKIX: verificationKeyPKIX,
	}, nil
}

func (s *Server) Sign(ctx context.Context, req *pb.SignJWTRequest) (*pb.SignJWTResponse, error) {
	header, signature, err := s.signFn([]byte(req.Claims))
	if err != nil {
		return nil, fmt.Errorf("threshold sign: %w", err)
	}
	fmt.Fprintf(os.Stderr, "[grpc] Sign() kid=%s\n", s.keyID)
	return &pb.SignJWTResponse{Header: header, Signature: signature}, nil
}

func (s *Server) FetchKeys(ctx context.Context, req *pb.FetchKeysRequest) (*pb.FetchKeysResponse, error) {
	fmt.Println("[grpc] FetchKeys()")
	return &pb.FetchKeysResponse{
		Keys: []*pb.Key{{
			KeyId: s.keyID,
			Key:   s.verificationKeyPKIX,
		}},
		DataTimestamp:      timestamppb.New(time.Now()),
		RefreshHintSeconds: 300,
	}, nil
}

func (s *Server) Metadata(ctx context.Context, req *pb.MetadataRequest) (*pb.MetadataResponse, error) {
	fmt.Println("[grpc] Metadata()")
	return &pb.MetadataResponse{MaxTokenExpirationSeconds: 3600}, nil
}

func ListenAndServe(socketPath string, srv *Server) error {
	_ = os.Remove(socketPath)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen unix %s: %w", socketPath, err)
	}
	grpcServer := grpc.NewServer()
	pb.RegisterExternalJWTSignerServer(grpcServer, srv)
	fmt.Printf("[grpc] Listening on unix://%s\n", socketPath)
	return grpcServer.Serve(listener)
}

func ListenAndServeTCP(addr string, srv *Server) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen tcp %s: %w", addr, err)
	}
	grpcServer := grpc.NewServer()
	pb.RegisterExternalJWTSignerServer(grpcServer, srv)
	fmt.Printf("[grpc] Listening on tcp://%s\n", addr)
	return grpcServer.Serve(listener)
}

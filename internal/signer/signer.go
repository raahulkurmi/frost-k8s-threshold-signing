// Package signer is one threshold RSA signer: it holds exactly one secret
// share and returns a signature share for a JWT signing input only after
// validating the header and applying its own claims policy.
package signer

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/niclabs/tcrsa"
	"golang.org/x/time/rate"

	"frost-k8s-threshold-signing/internal/audit"
	"frost-k8s-threshold-signing/internal/jwtfmt"
	"frost-k8s-threshold-signing/internal/keymeta"
	"frost-k8s-threshold-signing/internal/policy"
	"frost-k8s-threshold-signing/internal/wire"
)

// Config wires a signer. Every field except Now, Logger and MaxConcurrent is
// required.
type Config struct {
	ID     int
	Meta   *keymeta.Meta
	Share  *tcrsa.KeyShare
	Policy *policy.Policy
	Audit  *audit.Log
	Now    func() time.Time
	Logger *slog.Logger
	// MaxConcurrent bounds concurrent RSA share computations (admission
	// control, NOTES N46). 0 means runtime.NumCPU(). When all slots are busy a
	// request is shed immediately with 503 instead of queueing past the
	// coordinator's deadline.
	MaxConcurrent int
}

// Server handles POST /v1/sign-share and GET /healthz.
type Server struct {
	cfg     Config
	limiter *rate.Limiter
	slots   chan struct{}
	rsaOps  atomic.Int64
}

// testHookBeforeRSA, if set (tests only), runs while holding an admission
// slot, just before the RSA share computation.
var testHookBeforeRSA func()

// New validates cfg. The share must belong to this signer ID.
func New(cfg Config) (*Server, error) {
	switch {
	case cfg.Meta == nil:
		return nil, errors.New("signer: meta is required")
	case cfg.Share == nil:
		return nil, errors.New("signer: share is required")
	case cfg.Policy == nil:
		return nil, errors.New("signer: policy is required")
	case cfg.Audit == nil:
		return nil, errors.New("signer: audit log is required")
	case cfg.ID < 1 || cfg.ID > cfg.Meta.Parties:
		return nil, fmt.Errorf("signer: id %d outside [1,%d]", cfg.ID, cfg.Meta.Parties)
	case int(cfg.Share.Id) != cfg.ID:
		return nil, fmt.Errorf("signer: share index %d != signer id %d", cfg.Share.Id, cfg.ID)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.MaxConcurrent < 0 {
		return nil, fmt.Errorf("signer: MaxConcurrent %d < 0", cfg.MaxConcurrent)
	}
	if cfg.MaxConcurrent == 0 {
		cfg.MaxConcurrent = runtime.NumCPU()
	}
	r := cfg.Policy.Config().RateLimit
	return &Server{
		cfg:     cfg,
		limiter: rate.NewLimiter(rate.Limit(r.RequestsPerSecond), r.Burst),
		slots:   make(chan struct{}, cfg.MaxConcurrent),
	}, nil
}

// RSAOps returns how many RSA share computations this signer has performed.
func (s *Server) RSAOps() int64 { return s.rsaOps.Load() }

// MaxConcurrent returns the admission-control bound in effect.
func (s *Server) MaxConcurrent() int { return s.cfg.MaxConcurrent }

// Handler returns the HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+wire.SignSharePath, s.handleSignShare)
	mux.HandleFunc("GET "+wire.HealthPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "signer_id": s.cfg.ID, "kid": s.cfg.Meta.KID})
	})
	return mux
}

// Rejection is a refused request with its HTTP status.
type Rejection struct {
	Status int
	Kind   string // wire.ErrorResponse.Error
	Reason string
}

func (r *Rejection) Error() string { return r.Kind + ": " + r.Reason }

func reject(status int, kind, format string, a ...any) *Rejection {
	return &Rejection{Status: status, Kind: kind, Reason: fmt.Sprintf(format, a...)}
}

func peerName(r *http.Request) string {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 && len(r.TLS.PeerCertificates[0].DNSNames) > 0 {
		return r.TLS.PeerCertificates[0].DNSNames[0]
	}
	return ""
}

func (s *Server) handleSignShare(w http.ResponseWriter, r *http.Request) {
	body := http.MaxBytesReader(w, r.Body, wire.MaxRequestBytes)
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	var req wire.SignShareRequest
	var resp *wire.SignShareResponse
	var rej *Rejection
	if err := dec.Decode(&req); err != nil {
		rej = reject(http.StatusBadRequest, "bad_request", "request body: %v", err)
	} else if dec.More() {
		rej = reject(http.StatusBadRequest, "bad_request", "trailing data after request")
	} else {
		resp, rej = s.SignShare(r.Context(), req, peerName(r))
	}
	w.Header().Set("Content-Type", "application/json")
	if rej != nil {
		w.WriteHeader(rej.Status)
		_ = json.NewEncoder(w).Encode(wire.ErrorResponse{Error: rej.Kind, Reason: rej.Reason, RequestID: req.RequestID})
		return
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// SignShare validates req and, if every check passes, returns this signer's
// signature share. It hashes and pads the signing input itself (I8); it
// never accepts a digest or padded block from the caller.
//
// ctx is the request's context: if the coordinator has already given up
// (deadline, or quorum reached elsewhere and the request cancelled), no RSA
// work is done, and a share computed after cancellation is discarded (N46).
func (s *Server) SignShare(ctx context.Context, req wire.SignShareRequest, client string) (*wire.SignShareResponse, *Rejection) {
	start := s.cfg.Now()
	entry := audit.Entry{Time: start.UTC(), SignerID: s.cfg.ID, RequestID: req.RequestID, Client: client}
	if req.SigningInput != "" {
		sum := sha256.Sum256([]byte(req.SigningInput))
		entry.SigningInputSHA256 = hex.EncodeToString(sum[:])
	}
	deny := func(rej *Rejection) (*wire.SignShareResponse, *Rejection) {
		entry.Decision, entry.Reason = "deny", rej.Error()
		if err := s.cfg.Audit.Write(entry); err != nil {
			s.cfg.Logger.Error("audit write failed", "err", err)
		}
		s.cfg.Logger.Warn("sign-share denied", "request_id", req.RequestID, "reason", rej.Error(), "client", client)
		return nil, rej
	}

	if !s.limiter.Allow() {
		return deny(reject(http.StatusTooManyRequests, "rate_limited", "signer %d rate limit exceeded", s.cfg.ID))
	}
	if !wire.ValidRequestID(req.RequestID) {
		return deny(reject(http.StatusBadRequest, "bad_request", "request_id missing or invalid"))
	}
	headerSeg, payloadSeg, err := jwtfmt.SplitSigningInput(req.SigningInput)
	if err != nil {
		return deny(reject(http.StatusBadRequest, "bad_request", "%v", err))
	}
	if err := jwtfmt.CheckHeader(headerSeg, s.cfg.Meta.KID); err != nil {
		return deny(reject(http.StatusForbidden, "policy", "%v", err))
	}
	payload, err := jwtfmt.DecodeSegment(payloadSeg)
	if err != nil {
		return deny(reject(http.StatusBadRequest, "bad_request", "payload: %v", err))
	}
	decision, err := s.cfg.Policy.Evaluate(payload, start)
	if err != nil {
		return deny(reject(http.StatusForbidden, "policy", "%v", err))
	}
	entry.Sub, entry.Aud = decision.Subject, decision.Audiences

	// I8: hash and PKCS#1 v1.5-encode the exact signing input here.
	digest := sha256.Sum256([]byte(req.SigningInput))
	doc, err := tcrsa.PrepareDocumentHash(s.cfg.Meta.PublicKey.Size(), crypto.SHA256, digest[:])
	if err != nil {
		return deny(reject(http.StatusInternalServerError, "internal", "encode: %v", err))
	}
	// N46: never start RSA work for a caller that has already gone away.
	if err := ctx.Err(); err != nil {
		entry.Decision, entry.Reason = "cancelled", "before RSA: "+err.Error()
		_ = s.cfg.Audit.Write(entry)
		return nil, reject(http.StatusServiceUnavailable, "cancelled", "request cancelled before signing")
	}
	// N46: admission control. Take a slot without waiting; if all are busy,
	// shed now (503) rather than queue past the coordinator's deadline.
	select {
	case s.slots <- struct{}{}:
	default:
		entry.Decision, entry.Reason = "shed", fmt.Sprintf("overloaded: %d concurrent share computations in progress", s.cfg.MaxConcurrent)
		_ = s.cfg.Audit.Write(entry)
		return nil, reject(http.StatusServiceUnavailable, "overloaded", "signer %d at capacity", s.cfg.ID)
	}
	defer func() { <-s.slots }()
	// Record the allow decision before releasing the share; no audit, no share.
	entry.Decision = "allow"
	if err := s.cfg.Audit.Write(entry); err != nil {
		s.cfg.Logger.Error("audit write failed; refusing to sign", "err", err)
		return nil, reject(http.StatusInternalServerError, "internal", "audit log unavailable")
	}
	if testHookBeforeRSA != nil {
		testHookBeforeRSA()
	}
	s.rsaOps.Add(1)
	ss, err := s.cfg.Share.Sign(doc, crypto.SHA256, s.cfg.Meta.Tcrsa)
	if err != nil {
		return nil, reject(http.StatusInternalServerError, "internal", "sign: %v", err)
	}
	if err := ctx.Err(); err != nil {
		// Computed too late: the caller is gone. Do not release the share.
		s.cfg.Logger.Info("sign-share discarded: request cancelled during signing", "request_id", req.RequestID)
		return nil, reject(http.StatusServiceUnavailable, "cancelled", "request cancelled during signing")
	}
	ss = tamper(s.cfg.ID, ss)
	s.cfg.Logger.Info("sign-share", "request_id", req.RequestID, "sub", decision.Subject,
		"client", client, "latency_ms", float64(time.Since(start).Microseconds())/1000)
	return &wire.SignShareResponse{SignerID: s.cfg.ID, Share: wire.FromTcrsa(ss), RequestID: req.RequestID}, nil
}

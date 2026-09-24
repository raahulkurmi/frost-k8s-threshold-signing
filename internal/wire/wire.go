// Package wire defines the coordinator <-> signer HTTP API (POST /v1/sign-share).
// It carries only public values: the signing input and a signature share.
package wire

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"

	"github.com/niclabs/tcrsa"
)

const (
	SignSharePath = "/v1/sign-share"
	HealthPath    = "/healthz"
	// MaxRequestBytes bounds a sign-share request body.
	MaxRequestBytes = 64 << 10
	// MaxResponseBytes bounds a sign-share response body.
	MaxResponseBytes = 16 << 10
	maxRequestIDLen  = 128
)

// SignShareRequest is sent by the coordinator. SigningInput is the full JWS
// signing input base64url(header).base64url(payload); the signer hashes and
// pads it itself (I8). Unknown fields (e.g. a digest) are rejected.
type SignShareRequest struct {
	SigningInput string `json:"signing_input"`
	RequestID    string `json:"request_id"`
}

// SigShare is a tcrsa signature share, base64 std. The share's index is not
// carried here: it is the responding signer's authenticated identity.
type SigShare struct {
	Xi string `json:"xi"`
	C  string `json:"c"`
	Z  string `json:"z"`
}

// SignShareResponse is returned on success.
type SignShareResponse struct {
	SignerID  int      `json:"signer_id"`
	Share     SigShare `json:"share"`
	RequestID string   `json:"request_id"`
}

// ErrorResponse is returned with a non-200 status.
type ErrorResponse struct {
	Error     string `json:"error"` // "bad_request", "policy", "rate_limited", "internal"
	Reason    string `json:"reason"`
	RequestID string `json:"request_id,omitempty"`
}

// ValidRequestID accepts 1..128 chars of [A-Za-z0-9._-].
func ValidRequestID(s string) bool {
	if len(s) == 0 || len(s) > maxRequestIDLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// FromTcrsa encodes a signature share.
func FromTcrsa(s *tcrsa.SigShare) SigShare {
	e := base64.StdEncoding.EncodeToString
	return SigShare{Xi: e(s.Xi), C: e(s.C), Z: e(s.Z)}
}

// ToTcrsa decodes a share and attaches id, which the caller must take from the
// authenticated identity of the signer it came from (never from the payload).
// It rejects shares that are not well-formed for modulus n: empty values,
// Xi outside [1, n-1], or oversized C/Z. id is bounds-checked against parties
// because tcrsa's SigShare.Verify indexes VerificationKey.I[id-1] unchecked
// and panics otherwise (NOTES.md N5).
func (s SigShare) ToTcrsa(id, parties int, n *big.Int) (*tcrsa.SigShare, error) {
	if id < 1 || id > parties {
		return nil, fmt.Errorf("share id %d outside [1,%d]", id, parties)
	}
	d := base64.StdEncoding.DecodeString
	xi, err := d(s.Xi)
	if err != nil || len(xi) == 0 {
		return nil, errors.New("xi: missing or bad base64")
	}
	c, err := d(s.C)
	if err != nil || len(c) == 0 {
		return nil, errors.New("c: missing or bad base64")
	}
	z, err := d(s.Z)
	if err != nil || len(z) == 0 {
		return nil, errors.New("z: missing or bad base64")
	}
	x := new(big.Int).SetBytes(xi)
	if x.Sign() <= 0 || x.Cmp(n) >= 0 {
		return nil, errors.New("xi outside [1, n-1]")
	}
	if new(big.Int).SetBytes(c).Cmp(n) >= 0 {
		return nil, errors.New("c >= n")
	}
	// z = c*si + r with r < 2^(|n| + 2*256); bound it to reject oversized values.
	if len(z) > 3*len(n.Bytes()) {
		return nil, errors.New("z oversized")
	}
	return &tcrsa.SigShare{Id: uint16(id), Xi: xi, C: c, Z: z}, nil
}

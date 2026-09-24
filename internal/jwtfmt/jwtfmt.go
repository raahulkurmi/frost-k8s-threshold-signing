// Package jwtfmt defines the one JWT header this system issues and strict
// parsing of JWS signing inputs. The coordinator and signers share it so
// both sides agree byte-for-byte on what is signed.
package jwtfmt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	Alg = "RS256"
	Typ = "JWT"
	// MaxSigningInput bounds header.payload; service account claims are ~1 KB.
	MaxSigningInput = 16 << 10
	// MaxKIDLen matches kube-apiserver's validateJWTHeader limit.
	MaxKIDLen = 1024
)

// Header is the only permitted JWT header shape (kube-apiserver
// pkg/serviceaccount/externaljwt/plugin/plugin.go accepts exactly alg/kid/typ).
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

func validKID(kid string) error {
	if kid == "" || len(kid) > MaxKIDLen {
		return errors.New("kid empty or too long")
	}
	for _, c := range kid {
		if !isB64URL(byte(c)) || c > 127 {
			return fmt.Errorf("kid contains %q; only base64url characters are allowed", c)
		}
	}
	return nil
}

// EncodedHeader returns base64url(`{"alg":"RS256","typ":"JWT","kid":"<kid>"}`).
func EncodedHeader(kid string) (string, error) {
	if err := validKID(kid); err != nil {
		return "", err
	}
	b, err := json.Marshal(Header{Alg: Alg, Typ: Typ, Kid: kid})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ParseHeader strictly decodes a header segment: exactly alg, typ, kid.
func ParseHeader(seg string) (Header, error) {
	raw, err := DecodeSegment(seg)
	if err != nil {
		return Header{}, fmt.Errorf("header: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var h Header
	if err := dec.Decode(&h); err != nil {
		return Header{}, fmt.Errorf("header: %w", err)
	}
	if dec.More() {
		return Header{}, errors.New("header: trailing data")
	}
	return h, nil
}

// CheckHeader verifies that seg is exactly the canonical header for kid. It
// returns a specific reason for the common attacks (alg none/ES256, wrong kid,
// extra fields) before the byte-equality check.
func CheckHeader(seg, kid string) error {
	h, err := ParseHeader(seg)
	if err != nil {
		return err
	}
	if h.Alg != Alg {
		return fmt.Errorf("header alg %q, only %s is signed", h.Alg, Alg)
	}
	if h.Typ != Typ {
		return fmt.Errorf("header typ %q, want %s", h.Typ, Typ)
	}
	if h.Kid != kid {
		return fmt.Errorf("header kid %q does not match this key (%q)", h.Kid, kid)
	}
	want, err := EncodedHeader(kid)
	if err != nil {
		return err
	}
	if seg != want {
		return errors.New("header is not in canonical form")
	}
	return nil
}

// SplitSigningInput splits base64url(header).base64url(payload), enforcing
// exactly two non-empty base64url segments and a size bound.
func SplitSigningInput(s string) (header, payload string, err error) {
	if len(s) == 0 || len(s) > MaxSigningInput {
		return "", "", fmt.Errorf("signing input length %d outside (0, %d]", len(s), MaxSigningInput)
	}
	header, payload, ok := strings.Cut(s, ".")
	if !ok || header == "" || payload == "" || strings.Contains(payload, ".") {
		return "", "", errors.New("signing input must be exactly base64url(header).base64url(payload)")
	}
	if err := CheckSegment(header); err != nil {
		return "", "", fmt.Errorf("header segment: %w", err)
	}
	if err := CheckSegment(payload); err != nil {
		return "", "", fmt.Errorf("payload segment: %w", err)
	}
	return header, payload, nil
}

// CheckSegment verifies seg is non-empty unpadded base64url that decodes.
func CheckSegment(seg string) error {
	if seg == "" {
		return errors.New("empty segment")
	}
	for i := 0; i < len(seg); i++ {
		if !isB64URL(seg[i]) {
			return fmt.Errorf("invalid base64url character %q", seg[i])
		}
	}
	_, err := DecodeSegment(seg)
	return err
}

// DecodeSegment decodes strict unpadded base64url.
func DecodeSegment(seg string) ([]byte, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(seg)
	if err != nil {
		return nil, fmt.Errorf("bad base64url: %w", err)
	}
	return b, nil
}

func isB64URL(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}

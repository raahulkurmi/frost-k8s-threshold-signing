// Command signer is one threshold RSA signer. It loads exactly one secret
// share (its own), the public key metadata and a claims policy, and serves
// POST /v1/sign-share over mTLS to the coordinator only.
//
// Environment (all required unless noted; anything missing aborts startup):
//
//	SIGNER_ID      1..n
//	META_FILE      public-meta.json
//	SHARE_FILE     share-<SIGNER_ID>.json         (exactly one of SHARE_FILE / VAULT_ADDR)
//	VAULT_ADDR     Vault address; share read from <VAULT_MOUNT>/frost-k8s/signer-<SIGNER_ID>
//	VAULT_TOKEN    required with VAULT_ADDR
//	VAULT_MOUNT    optional, default "secret"
//	POLICY_FILE    claims policy JSON
//	AUDIT_LOG      audit log path (JSON lines)
//	TLS_CERT, TLS_KEY   this signer's cert (SAN exactly DNS:signer-<SIGNER_ID>)
//	TLS_CA         CA that issued the coordinator's client cert
//	LISTEN_ADDR    optional, default ":8443"
//	SIGNER_MAX_CONCURRENT optional, default runtime.NumCPU(): concurrent RSA
//	               computations before requests are shed with 503 (N46)
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/niclabs/tcrsa"

	"frost-k8s-threshold-signing/internal/audit"
	"frost-k8s-threshold-signing/internal/keymeta"
	"frost-k8s-threshold-signing/internal/keyshare"
	"frost-k8s-threshold-signing/internal/policy"
	"frost-k8s-threshold-signing/internal/signer"
	"frost-k8s-threshold-signing/internal/tlsconf"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(context.Background(), os.Getenv, logger); err != nil {
		logger.Error("signer failed", "err", err.Error())
		os.Exit(1)
	}
}

// settings is the validated startup configuration.
type settings struct {
	ID      int
	Meta    *keymeta.Meta
	Share   *tcrsa.KeyShare
	Policy  *policy.Policy
	Audit   string
	Listen  string
	MaxConc int
	Cert    string
	Key     string
	CA      string
}

func require(getenv func(string) string, name string) (string, error) {
	v := getenv(name)
	if v == "" {
		return "", fmt.Errorf("%s is not set", name)
	}
	return v, nil
}

// load reads and validates all configuration. It is the only place a share
// is loaded, and it loads exactly one: SIGNER_ID's.
func load(ctx context.Context, getenv func(string) string) (*settings, error) {
	var s settings
	idStr, err := require(getenv, "SIGNER_ID")
	if err != nil {
		return nil, err
	}
	if s.ID, err = strconv.Atoi(idStr); err != nil {
		return nil, fmt.Errorf("SIGNER_ID %q is not an integer", idStr)
	}
	metaPath, err := require(getenv, "META_FILE")
	if err != nil {
		return nil, err
	}
	if s.Meta, err = keymeta.Load(metaPath); err != nil {
		return nil, err
	}
	if s.ID < 1 || s.ID > s.Meta.Parties {
		return nil, fmt.Errorf("SIGNER_ID %d outside [1,%d]", s.ID, s.Meta.Parties)
	}

	shareFile, vaultAddr := getenv("SHARE_FILE"), getenv("VAULT_ADDR")
	switch {
	case shareFile != "" && vaultAddr != "":
		return nil, errors.New("both SHARE_FILE and VAULT_ADDR are set; configure exactly one share source")
	case vaultAddr != "":
		token, err := require(getenv, "VAULT_TOKEN")
		if err != nil {
			return nil, fmt.Errorf("VAULT_ADDR is set but %w", err)
		}
		mount := getenv("VAULT_MOUNT")
		if mount == "" {
			mount = "secret"
		}
		if s.Share, err = keyshare.LoadFromVault(ctx, vaultAddr, token, mount, s.Meta, s.ID); err != nil {
			return nil, err
		}
	case shareFile != "":
		if s.Share, err = keyshare.Load(shareFile, s.Meta, s.ID); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("no share source: set SHARE_FILE or VAULT_ADDR")
	}

	policyPath, err := require(getenv, "POLICY_FILE")
	if err != nil {
		return nil, err
	}
	if s.Policy, err = policy.Load(policyPath); err != nil {
		return nil, err
	}
	for _, p := range []struct {
		dst  *string
		name string
	}{{&s.Audit, "AUDIT_LOG"}, {&s.Cert, "TLS_CERT"}, {&s.Key, "TLS_KEY"}, {&s.CA, "TLS_CA"}} {
		if *p.dst, err = require(getenv, p.name); err != nil {
			return nil, err
		}
	}
	if v := getenv("SIGNER_MAX_CONCURRENT"); v != "" {
		if s.MaxConc, err = strconv.Atoi(v); err != nil || s.MaxConc < 1 {
			return nil, fmt.Errorf("SIGNER_MAX_CONCURRENT %q must be a positive integer", v)
		}
	}
	s.Listen = getenv("LISTEN_ADDR")
	if s.Listen == "" {
		s.Listen = ":8443"
	}
	return &s, nil
}

func run(ctx context.Context, getenv func(string) string, logger *slog.Logger) error {
	s, err := load(ctx, getenv)
	if err != nil {
		return err
	}
	tlsCfg, err := tlsconf.SignerServer(s.Cert, s.Key, s.CA, s.ID)
	if err != nil {
		return err
	}
	auditLog, err := audit.Open(s.Audit)
	if err != nil {
		return err
	}
	defer auditLog.Close()
	srv, err := signer.New(signer.Config{ID: s.ID, Meta: s.Meta, Share: s.Share, Policy: s.Policy, Audit: auditLog, Logger: logger, MaxConcurrent: s.MaxConc})
	if err != nil {
		return err
	}
	hs := &http.Server{
		Addr:              s.Listen,
		Handler:           srv.Handler(),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	logger.Info("signer ready", "signer_id", s.ID, "kid", s.Meta.KID, "threshold", s.Meta.Threshold,
		"parties", s.Meta.Parties, "listen", s.Listen, "max_token_seconds", s.Policy.MaxTokenSeconds(), "max_concurrent", srv.MaxConcurrent())

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- hs.ListenAndServeTLS("", "") }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return hs.Shutdown(shutdownCtx)
	}
}

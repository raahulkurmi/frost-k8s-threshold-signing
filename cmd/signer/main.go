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
//	VAULT_DEV_ALLOW_HTTP  optional, "1" permits a plain http:// VAULT_ADDR (local
//	               development only); otherwise VAULT_ADDR must be https://
//	POLICY_FILE    claims policy JSON
//	AUDIT_LOG      audit log path (JSON lines)
//	TLS_CERT, TLS_KEY   this signer's cert (SAN exactly DNS:signer-<SIGNER_ID>)
//	TLS_CA         CA that issued the coordinator's client cert
//	LISTEN_ADDR    optional, default ":8443"
//	SIGNER_MAX_CONCURRENT optional, default runtime.NumCPU(): concurrent RSA
//	               computations (N46)
//	SIGNER_MAX_QUEUE optional, default 64: requests that may wait for a slot;
//	               a request waits only while it can still meet its deadline (N48)
//	SIGNER_MAX_DEADLINE optional, Go duration, default 4s: cap on the caller's
//	               deadline header (N76)
//	SIGNER_QUEUE_SAMPLE optional, Go duration, off by default: log queue length
//	               and busy slots at this interval (benchmark instrumentation, N76)
//	SIGNER_ADMISSION optional, n48 (default) | priority: priority-consistent
//	               admission before the N48 queue (N76). EVALUATED, NOT RECOMMENDED:
//	               neither controller met its pre-registered rules (NOTES N78, N81). priority needs the
//	               signers' shared key: PRIORITY_KEY_FILE (priority.key from the
//	               dealer), or with VAULT_ADDR the key at <VAULT_MOUNT>/frost-k8s/priority-key
//	SIGNER_PRIORITY optional (priority admission only), stable (default) | request:
//	               p from the claims' stable identity (sub + pod uid) per epoch, or
//	               from the request_id (a new draw per retry) (N77)
//	SIGNER_PRIORITY_CONTROLLER optional, v2 (default) | v1: admission-level controller
//	               (v2: docs/PRIORITY_ADMISSION_V2.md; v1 reproduces N76-N78)
//	SIGNER_PRIORITY_EPOCH optional, default 2m (stable): whole seconds, >= 10s
//	SIGNER_PRIORITY_ROTATION optional, default 32 (stable): power of two in 2..64,
//	               at least 1/(admission floor) = 20 with the 5 % floor
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
	"frost-k8s-threshold-signing/internal/prioritykey"
	"frost-k8s-threshold-signing/internal/signer"
	"frost-k8s-threshold-signing/internal/tlsconf"
	"frost-k8s-threshold-signing/internal/vaultclient"
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
	ID       int
	Meta     *keymeta.Meta
	Share    *tcrsa.KeyShare
	Policy   *policy.Policy
	Audit    string
	Listen   string
	MaxConc  int
	MaxQueue int
	MaxDL    time.Duration
	QSample  time.Duration
	PrioKey  []byte
	Adm      signer.AdmissionConfig
	Cert     string
	Key      string
	CA       string
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
		// Audit E-1: https only (plain http only with VAULT_DEV_ALLOW_HTTP=1).
		if err := vaultclient.CheckAddrEnv(vaultAddr, getenv); err != nil {
			return nil, err
		}
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
	if v := getenv("SIGNER_MAX_QUEUE"); v != "" {
		if s.MaxQueue, err = strconv.Atoi(v); err != nil || s.MaxQueue < 1 {
			return nil, fmt.Errorf("SIGNER_MAX_QUEUE %q must be a positive integer", v)
		}
	}
	if v := getenv("SIGNER_MAX_DEADLINE"); v != "" {
		if s.MaxDL, err = time.ParseDuration(v); err != nil || s.MaxDL <= 0 {
			return nil, fmt.Errorf("SIGNER_MAX_DEADLINE %q is not a positive duration", v)
		}
	}
	if v := getenv("SIGNER_QUEUE_SAMPLE"); v != "" {
		if s.QSample, err = time.ParseDuration(v); err != nil || s.QSample < 10*time.Millisecond {
			return nil, fmt.Errorf("SIGNER_QUEUE_SAMPLE %q must be a duration >= 10ms", v)
		}
	}
	switch mode := getenv("SIGNER_ADMISSION"); mode {
	case "", "n48":
		if getenv("PRIORITY_KEY_FILE") != "" {
			return nil, errors.New("PRIORITY_KEY_FILE is set but SIGNER_ADMISSION is not priority")
		}
	case "priority":
		if f := getenv("PRIORITY_KEY_FILE"); f != "" {
			if s.PrioKey, err = prioritykey.Load(f, s.Meta.KID); err != nil {
				return nil, err
			}
		} else if vaultAddr != "" {
			mount := getenv("VAULT_MOUNT")
			if mount == "" {
				mount = "secret"
			}
			if s.PrioKey, err = prioritykey.LoadFromVault(ctx, vaultAddr, getenv("VAULT_TOKEN"), mount, s.Meta.KID); err != nil {
				return nil, err
			}
		} else {
			return nil, errors.New("SIGNER_ADMISSION=priority needs PRIORITY_KEY_FILE (or VAULT_ADDR)")
		}
	default:
		return nil, fmt.Errorf("SIGNER_ADMISSION %q must be n48 or priority", mode)
	}
	pm, pe, pr, pc := getenv("SIGNER_PRIORITY"), getenv("SIGNER_PRIORITY_EPOCH"), getenv("SIGNER_PRIORITY_ROTATION"), getenv("SIGNER_PRIORITY_CONTROLLER")
	if s.PrioKey == nil && (pm != "" || pe != "" || pr != "" || pc != "") {
		return nil, errors.New("SIGNER_PRIORITY* is set but SIGNER_ADMISSION is not priority")
	}
	switch pm {
	case "", "stable":
		s.Adm.Mode = signer.PriorityStable
	case "request":
		s.Adm.Mode = signer.PriorityRequest
	default:
		return nil, fmt.Errorf("SIGNER_PRIORITY %q must be stable or request", pm)
	}
	switch pc {
	case "", "v2":
		s.Adm.Controller = "v2"
	case "v1":
		s.Adm.Controller = "v1"
	default:
		return nil, fmt.Errorf("SIGNER_PRIORITY_CONTROLLER %q must be v1 or v2", pc)
	}
	if pe != "" {
		if s.Adm.Epoch, err = time.ParseDuration(pe); err != nil || s.Adm.Epoch < 10*time.Second || s.Adm.Epoch%time.Second != 0 {
			return nil, fmt.Errorf("SIGNER_PRIORITY_EPOCH %q must be whole seconds >= 10s", pe)
		}
	}
	if pr != "" {
		if s.Adm.Rotation, err = strconv.Atoi(pr); err != nil || !signer.StableRotationOK(s.Adm.Rotation, 0.05) {
			return nil, fmt.Errorf("SIGNER_PRIORITY_ROTATION %q must be a power of two in 32..64 (at least 1/floor with the 5%% floor)", pr)
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
	srv, err := signer.New(signer.Config{ID: s.ID, Meta: s.Meta, Share: s.Share, Policy: s.Policy, Audit: auditLog, Logger: logger, MaxConcurrent: s.MaxConc, MaxQueue: s.MaxQueue,
		MaxDeadline: s.MaxDL, PriorityKey: s.PrioKey, Admission: s.Adm})
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
		"parties", s.Meta.Parties, "listen", s.Listen, "max_token_seconds", s.Policy.MaxTokenSeconds(), "max_concurrent", srv.MaxConcurrent(), "max_queue", srv.MaxQueue(),
		"admission", map[bool]string{true: "priority", false: "n48"}[s.PrioKey != nil], "max_deadline", srv.MaxDeadline().String(),
		"priority", prioMode(srv), "priority_epoch", prioEpoch(srv), "priority_rotation", prioRotation(srv), "priority_controller", prioController(srv))

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if s.QSample > 0 {
		go srv.SampleQueue(ctx, s.QSample)
	}
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

func prioMode(s *signer.Server) string {
	if c := s.PriorityConfig(); c != nil {
		return string(c.Mode)
	}
	return ""
}

func prioEpoch(s *signer.Server) string {
	if c := s.PriorityConfig(); c != nil && c.Mode == signer.PriorityStable {
		return c.Epoch.String()
	}
	return ""
}

func prioRotation(s *signer.Server) int {
	if c := s.PriorityConfig(); c != nil && c.Mode == signer.PriorityStable {
		return c.Rotation
	}
	return 0
}

func prioController(s *signer.Server) string {
	if c := s.PriorityConfig(); c != nil {
		return c.Controller
	}
	return ""
}
